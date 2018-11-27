/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   strncat.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: amaindro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/11/23 12:42:22 by amaindro          #+#    #+#             */
/*   Updated: 2015/11/26 19:06:05 by amaindro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <string.h>
#include "libft.h"

char	*ft_strncat(char *dst, const char *src, size_t n)
{
	size_t	i;
	size_t	end;

	i = 0;
	end = ft_strlen(dst);
	while (i < n && src[i] != '\0')
	{
		dst[i + end] = src[i];
		i++;
	}
	dst[i + end] = '\0';
	return (dst);
}
